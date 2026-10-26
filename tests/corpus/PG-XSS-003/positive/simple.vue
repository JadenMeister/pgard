<!-- corpus: expect=PG-XSS-003 -->
<template>
  <div v-html="comment"></div>
</template>
<script setup>
defineProps({ comment: String });
</script>
